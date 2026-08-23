import { ethers } from "ethers";
import { bls, BLS_DST, encodeG2Point, sigs } from "../../utils/bls.util.js";
import { buildSignerMask, MAX_VALIDATORS } from "../audit/slash-consensus.js";

const ABI = ethers.AbiCoder.defaultAbiCoder();

export const REPCREDIT_SCHEMA_VERSION = "repcredit-reputation-v1";

/** The exact structured request whose seven on-chain fields are BLS-signed. */
export interface RepCreditProposal {
  schemaVersion: typeof REPCREDIT_SCHEMA_VERSION;
  proposalId: string;
  operator: string;
  slashLevel: number;
  users: string[];
  scores: string[];
  epoch: string;
  chainId: string;
  messageHash: string;
}

export interface RepCreditCoSignResponse {
  slot: number;
  signerNodeId: string;
  signerPublicKey: string;
  signatureCompact: string;
  messageHash: string;
}

export interface RepCreditAggregate {
  signerMask: string;
  sigG2: string;
  signatureCompact: string;
  proof: string;
  messageHash: string;
  slots: number[];
}

function uint256(value: string, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > ethers.MaxUint256) {
    throw new Error(`${field} is outside uint256`);
  }
  return parsed;
}

function normalizedProposalValues(proposal: RepCreditProposal): {
  proposalId: bigint;
  users: string[];
  scores: bigint[];
  epoch: bigint;
  chainId: bigint;
} {
  if (!proposal || proposal.schemaVersion !== REPCREDIT_SCHEMA_VERSION) {
    throw new Error(`schemaVersion must equal ${REPCREDIT_SCHEMA_VERSION}`);
  }
  if (proposal.operator !== ethers.ZeroAddress) {
    throw new Error("RepCredit reputation proposal operator must be the zero address");
  }
  if (proposal.slashLevel !== 0) {
    throw new Error("RepCredit reputation proposal slashLevel must be 0");
  }
  if (!Array.isArray(proposal.users) || proposal.users.length < 1 || proposal.users.length > 200) {
    throw new Error("users must contain between 1 and 200 addresses");
  }
  if (!Array.isArray(proposal.scores) || proposal.scores.length !== proposal.users.length) {
    throw new Error("scores length must equal users length");
  }

  const users = proposal.users.map((user, index) => {
    try {
      return ethers.getAddress(user);
    } catch {
      throw new Error(`users[${index}] is not an address`);
    }
  });
  if (new Set(users.map(user => user.toLowerCase())).size !== users.length) {
    throw new Error("users must not contain duplicates");
  }

  return {
    proposalId: uint256(proposal.proposalId, "proposalId"),
    users,
    scores: proposal.scores.map((score, index) => uint256(score, `scores[${index}]`)),
    epoch: uint256(proposal.epoch, "epoch"),
    chainId: uint256(proposal.chainId, "chainId"),
  };
}

/** Byte-identical to Registry.batchUpdateGlobalReputation's expected BLS hash. */
export function buildRepCreditMessageHash(proposal: RepCreditProposal): string {
  const value = normalizedProposalValues(proposal);
  return ethers.keccak256(
    ABI.encode(
      ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256"],
      [
        value.proposalId,
        ethers.ZeroAddress,
        0,
        value.users,
        value.scores,
        value.epoch,
        value.chainId,
      ]
    )
  );
}

/** Validate all caller fields and bind chainId to the node's own RPC network. */
export function validateRepCreditProposal(
  proposal: RepCreditProposal,
  localChainId: bigint | number
): string {
  const local = BigInt(localChainId);
  const value = normalizedProposalValues(proposal);
  if (value.chainId !== local) {
    throw new Error(`chainId mismatch: request=${value.chainId}, local=${local}`);
  }
  if (!ethers.isHexString(proposal.messageHash, 32)) {
    throw new Error("messageHash must be exactly 32 bytes");
  }
  const localHash = buildRepCreditMessageHash(proposal);
  if (localHash.toLowerCase() !== proposal.messageHash.toLowerCase()) {
    throw new Error("messageHash does not match the locally recomputed proposal hash");
  }
  return localHash;
}

export function encodeRepCreditPublicKey(publicKey: string): string {
  const point = bls.G1.Point.fromHex(publicKey.replace(/^0x/, ""));
  const affine = point.toAffine();
  const result = new Uint8Array(128);
  const x = Buffer.from(affine.x.toString(16).padStart(96, "0"), "hex");
  const y = Buffer.from(affine.y.toString(16).padStart(96, "0"), "hex");
  result.set(x, 16);
  result.set(y, 80);
  return ethers.hexlify(result).toLowerCase();
}

/**
 * Verify every compact response, bind it to the active on-chain key at its slot,
 * reject duplicates/under-threshold sets, and emit the production proof wire.
 */
export async function aggregateRepCreditResponses(
  proposal: RepCreditProposal,
  localChainId: bigint | number,
  responses: RepCreditCoSignResponse[],
  threshold: number,
  resolveOnChainKey: (slot: number) => Promise<string | null>
): Promise<RepCreditAggregate> {
  const messageHash = validateRepCreditProposal(proposal, localChainId);
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > MAX_VALIDATORS) {
    throw new Error(`threshold must be an integer in [1, ${MAX_VALIDATORS}]`);
  }
  if (!Array.isArray(responses) || responses.length < threshold) {
    throw new Error(`only ${responses?.length ?? 0} response(s), need ${threshold}`);
  }

  const seenSlots = new Set<number>();
  const signatures: ReturnType<typeof sigs.Signature.fromHex>[] = [];
  const slots: number[] = [];
  const messagePoint = await bls.G2.hashToCurve(ethers.getBytes(messageHash), { DST: BLS_DST });

  for (const response of responses) {
    if (!Number.isInteger(response.slot) || response.slot < 1 || response.slot > MAX_VALIDATORS) {
      throw new Error(`response slot ${response.slot} is outside [1, ${MAX_VALIDATORS}]`);
    }
    if (seenSlots.has(response.slot)) {
      throw new Error(`duplicate validator slot ${response.slot}`);
    }
    seenSlots.add(response.slot);
    if (String(response.messageHash).toLowerCase() !== messageHash.toLowerCase()) {
      throw new Error(`slot ${response.slot} signed a different messageHash`);
    }

    let publicKey: ReturnType<typeof bls.G1.Point.fromHex>;
    let signature: ReturnType<typeof sigs.Signature.fromHex>;
    try {
      publicKey = bls.G1.Point.fromHex(response.signerPublicKey.replace(/^0x/, ""));
      signature = sigs.Signature.fromHex(response.signatureCompact.replace(/^0x/, ""));
    } catch {
      throw new Error(`slot ${response.slot} returned malformed BLS material`);
    }
    if (!(await sigs.verify(signature, messagePoint, publicKey))) {
      throw new Error(`slot ${response.slot} returned an invalid signature`);
    }

    const onChainKey = await resolveOnChainKey(response.slot);
    if (!onChainKey) {
      throw new Error(`slot ${response.slot} is not active on-chain`);
    }
    if (encodeRepCreditPublicKey(response.signerPublicKey) !== onChainKey.toLowerCase()) {
      throw new Error(`slot ${response.slot} public key does not match on-chain registration`);
    }
    signatures.push(signature);
    slots.push(response.slot);
  }

  if (slots.length < threshold) {
    throw new Error(`only ${slots.length} valid unique slot(s), need ${threshold}`);
  }
  slots.sort((a, b) => a - b);
  const aggregate = sigs.aggregateSignatures(signatures);
  const sigG2 = ethers.hexlify(encodeG2Point(aggregate));
  const signerMask = buildSignerMask(slots);
  return {
    signerMask: signerMask.toString(),
    sigG2,
    signatureCompact: `0x${aggregate.toHex()}`,
    proof: ABI.encode(["uint256", "bytes"], [signerMask, sigG2]),
    messageHash,
    slots,
  };
}
