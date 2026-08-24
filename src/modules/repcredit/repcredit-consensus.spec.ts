import { ethers } from "ethers";
import { bls, BLS_DST, sigs } from "../../utils/bls.util.js";
import {
  aggregateRepCreditResponses,
  aggregateRepCreditSlashResponses,
  buildRepCreditMessageHash,
  buildRepCreditSlashMessageHash,
  encodeRepCreditPublicKey,
  REPCREDIT_SCHEMA_VERSION,
  REPCREDIT_SLASH_SCHEMA_VERSION,
  RepCreditCoSignResponse,
  RepCreditProposal,
  RepCreditSlashProposal,
  validateRepCreditProposal,
  validateRepCreditSlashProposal,
} from "./repcredit-consensus.js";

const EXPECTED_HASH = "0x9678641096f5fe0d99c0e0243dd141fe32321dfb4793846b5ae5ce2756234c24";
const EXPECTED_SLASH_HASH = "0x2d504c1c31ff3e9fd13ddfd05a943df6cd8ee4128f816ce3169c11794905dfa1";
const PRIVATE_KEYS = [1n, 2n, 3n].map(value =>
  ethers.getBytes(ethers.zeroPadValue(ethers.toBeHex(value), 32))
);

function proposal(overrides: Partial<RepCreditProposal> = {}): RepCreditProposal {
  return {
    schemaVersion: REPCREDIT_SCHEMA_VERSION,
    proposalId: "42",
    operator: ethers.ZeroAddress,
    slashLevel: 0,
    users: [
      "0x00000000000000000000000000000000000000a1",
      "0x00000000000000000000000000000000000000b2",
    ],
    scores: ["100", "50"],
    epoch: "7",
    chainId: "31337",
    messageHash: EXPECTED_HASH,
    ...overrides,
  };
}

function slashProposal(overrides: Partial<RepCreditSlashProposal> = {}): RepCreditSlashProposal {
  return {
    schemaVersion: REPCREDIT_SLASH_SCHEMA_VERSION,
    proposalId: "84",
    operator: ethers.ZeroAddress,
    slashLevel: 1,
    epoch: "9",
    chainId: "31337",
    evidenceHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
    messageHash: EXPECTED_SLASH_HASH,
    ...overrides,
  };
}

async function response(
  slot: number,
  messageHash = EXPECTED_HASH,
  signedHash = messageHash
): Promise<RepCreditCoSignResponse> {
  const privateKey = PRIVATE_KEYS[slot - 1];
  const publicKey = sigs.getPublicKey(privateKey);
  const messagePoint = await bls.G2.hashToCurve(ethers.getBytes(signedHash), { DST: BLS_DST });
  const signature = sigs.sign(messagePoint, privateKey);
  return {
    slot,
    signerNodeId: `node-${slot}`,
    signerPublicKey: `0x${publicKey.toHex()}`,
    signatureCompact: `0x${signature.toHex()}`,
    messageHash,
  };
}

function onChainResolver(responses: RepCreditCoSignResponse[]) {
  const keys = new Map(
    responses.map(item => [item.slot, encodeRepCreditPublicKey(item.signerPublicKey)])
  );
  return async (slot: number): Promise<string | null> => keys.get(slot) ?? null;
}

describe("RepCredit structured reputation quorum", () => {
  it("matches the Solidity Registry hash preimage exactly", () => {
    expect(buildRepCreditMessageHash(proposal())).toBe(EXPECTED_HASH);
    expect(validateRepCreditProposal(proposal(), 31337)).toBe(EXPECTED_HASH);
  });

  it("rejects a request whose chainId differs from the node's local RPC", () => {
    const wrongChain = proposal({ chainId: "1" });
    wrongChain.messageHash = buildRepCreditMessageHash(wrongChain);
    expect(() => validateRepCreditProposal(wrongChain, 31337)).toThrow(/chainId mismatch/);
  });

  it("aggregates three independently generated signatures into signerMask 7", async () => {
    const responses = await Promise.all([response(1), response(2), response(3)]);
    const result = await aggregateRepCreditResponses(
      proposal(),
      31337,
      responses,
      3,
      onChainResolver(responses)
    );
    expect(result.signerMask).toBe("7");
    expect(result.slots).toEqual([1, 2, 3]);
    expect(ethers.AbiCoder.defaultAbiCoder().decode(["uint256", "bytes"], result.proof)[0]).toBe(
      7n
    );
  });

  it("rejects duplicate validator slots instead of double-counting them", async () => {
    const first = await response(1);
    const duplicate = { ...(await response(1)), signerNodeId: "duplicate-node" };
    await expect(
      aggregateRepCreditResponses(
        proposal(),
        31337,
        [first, duplicate],
        2,
        onChainResolver([first])
      )
    ).rejects.toThrow(/duplicate validator slot 1/);
  });

  it("rejects an invalid signature even when the claimed messageHash is correct", async () => {
    const bad = await response(1, EXPECTED_HASH, ethers.keccak256(ethers.toUtf8Bytes("wrong")));
    await expect(
      aggregateRepCreditResponses(proposal(), 31337, [bad], 1, onChainResolver([bad]))
    ).rejects.toThrow(/invalid signature/);
  });

  it("rejects a response set below the configured threshold", async () => {
    const only = await response(1);
    await expect(
      aggregateRepCreditResponses(proposal(), 31337, [only], 2, onChainResolver([only]))
    ).rejects.toThrow(/only 1 response.*need 2/);
  });
});

describe("RepCredit structured slash-only quorum", () => {
  it("matches the Solidity slash-only hash preimage exactly", () => {
    expect(buildRepCreditSlashMessageHash(slashProposal())).toBe(EXPECTED_SLASH_HASH);
    expect(validateRepCreditSlashProposal(slashProposal(), 31337)).toBe(EXPECTED_SLASH_HASH);
  });

  it("rejects wrong-chain and caller-supplied mismatched hashes", () => {
    const wrongChain = slashProposal({ chainId: "1" });
    wrongChain.messageHash = buildRepCreditSlashMessageHash(wrongChain);
    expect(() => validateRepCreditSlashProposal(wrongChain, 31337)).toThrow(/chainId mismatch/);
    expect(() =>
      validateRepCreditSlashProposal(
        slashProposal({ messageHash: ethers.keccak256(ethers.toUtf8Bytes("wrong")) }),
        31337
      )
    ).toThrow(/locally recomputed slash proposal hash/);
  });

  it("aggregates three independently generated slash signatures into signerMask 7", async () => {
    const responses = await Promise.all([
      response(1, EXPECTED_SLASH_HASH),
      response(2, EXPECTED_SLASH_HASH),
      response(3, EXPECTED_SLASH_HASH),
    ]);
    const result = await aggregateRepCreditSlashResponses(
      slashProposal(),
      31337,
      responses,
      3,
      onChainResolver(responses)
    );
    expect(result.signerMask).toBe("7");
    expect(result.slots).toEqual([1, 2, 3]);
  });
});
