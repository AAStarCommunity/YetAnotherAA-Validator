import { ethers } from "ethers";
import {
  SlashLevel,
  QUEUE_SLASH_TAG,
  PendingSlotCoSigner,
  buildQueueMessageHash,
  buildExecuteMessageHash,
  encodeProof,
} from "./slash-consensus.js";

const OPERATOR = ethers.getAddress("0x" + "12".repeat(20));
const EVIDENCE_HASH = "0x" + "cd".repeat(32);
const CHAIN_ID = 11155111;

describe("slash-consensus primitives (SP #329)", () => {
  it("QUEUE_SLASH_TAG is keccak256 of the UTF-8 literal, matching Solidity keccak256(\"QUEUE_SLASH\")", () => {
    expect(QUEUE_SLASH_TAG).toBe(ethers.keccak256(ethers.toUtf8Bytes("QUEUE_SLASH")));
  });

  it("SlashLevel enum matches the on-chain values (WARNING=0, MINOR=1, MAJOR=2)", () => {
    expect(SlashLevel.WARNING).toBe(0);
    expect(SlashLevel.MINOR).toBe(1);
    expect(SlashLevel.MAJOR).toBe(2);
  });

  it("buildQueueMessageHash byte-matches a hand-computed 5-field AbiCoder reference (with domain tag)", () => {
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      new ethers.AbiCoder().encode(
        ["bytes32", "address", "uint8", "uint256", "uint256"],
        [
          ethers.keccak256(ethers.toUtf8Bytes("QUEUE_SLASH")),
          OPERATOR,
          slashLevel,
          epoch,
          CHAIN_ID,
        ]
      )
    );
    expect(buildQueueMessageHash(OPERATOR, slashLevel, epoch, CHAIN_ID)).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("buildExecuteMessageHash byte-matches a hand-computed 8-field reference (empty rep arrays + evidenceHash)", () => {
    const proposalId = 42n;
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      new ethers.AbiCoder().encode(
        ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
        [proposalId, OPERATOR, slashLevel, [], [], epoch, CHAIN_ID, EVIDENCE_HASH]
      )
    );
    expect(
      buildExecuteMessageHash(proposalId, OPERATOR, slashLevel, epoch, CHAIN_ID, EVIDENCE_HASH)
    ).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("the queue and execute preimages are distinct (domain separation holds)", () => {
    const epoch = 1_700_000;
    const queue = buildQueueMessageHash(OPERATOR, SlashLevel.MINOR, epoch, CHAIN_ID);
    const exec = buildExecuteMessageHash(1n, OPERATOR, SlashLevel.MINOR, epoch, CHAIN_ID, EVIDENCE_HASH);
    expect(queue).not.toBe(exec);
  });

  it("buildExecuteMessageHash is sensitive to evidenceHash (evidence binding is real)", () => {
    const a = buildExecuteMessageHash(1n, OPERATOR, 1, 5, CHAIN_ID, "0x" + "11".repeat(32));
    const b = buildExecuteMessageHash(1n, OPERATOR, 1, 5, CHAIN_ID, "0x" + "22".repeat(32));
    expect(a).not.toBe(b);
  });

  it("encodeProof produces abi.encode(uint256 signerMask, bytes sigG2) and round-trips", () => {
    const signerMask = 0b101n;
    const sigG2 = "0x" + "ab".repeat(64);
    const encoded = encodeProof(signerMask, sigG2);
    // Matches a direct AbiCoder reference.
    expect(encoded).toBe(new ethers.AbiCoder().encode(["uint256", "bytes"], [signerMask, sigG2]));
    // And decodes back to the same values.
    const [mask, sig] = new ethers.AbiCoder().decode(["uint256", "bytes"], encoded);
    expect(mask).toBe(signerMask);
    expect(sig).toBe(sigG2);
  });

  it("PendingSlotCoSigner fails closed: coSign throws the deferred-slot error", async () => {
    const coSigner = new PendingSlotCoSigner();
    await expect(coSigner.coSign("0x" + "00".repeat(32))).rejects.toThrow(
      /quorum co-sign deferred.*registerBLSPublicKey.*24h timelock/s
    );
  });
});
