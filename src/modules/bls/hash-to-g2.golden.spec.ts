import { ethers } from "ethers";
import { bls, BLS_DST, encodeG2Point } from "../../utils/bls.util.js";

/**
 * Cross-repo GOLDEN VECTOR — DVT BLS signing format (#42 conflict #1, decision B).
 *
 * #42 finalized the DVT signing preimage as decision B (option A was redundant
 * because EntryPoint.getUserOpHash already binds account/chainId/nonce/EntryPoint):
 *
 *     messagePoint = hash_to_curve( bytes(userOpHash), DST )
 *     DST          = BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
 *
 * messagePoint is NOT transmitted — it is recomputed on-chain by airaccount-contract
 * (#45, v0.18.0-beta.2) and by this node identically. This test is the off-chain
 * half of the shared golden vector: it pins a fixed (userOpHash -> messagePoint)
 * pair so any drift in the curve library (@noble/curves ^2.0.1), the DST, or the
 * EIP-2537 G2 encoding turns CI red. The SAME pair must be asserted by
 * airaccount-contract's test/HashToG2Golden.t.sol so all repos stay byte-identical.
 *
 * ⚠️ If this vector ever needs to change, it is a CROSS-REPO breaking change:
 * update #42 and every repo's golden test together — never silently re-baseline.
 */
describe("DVT BLS signing — golden vector (hash_to_curve(userOpHash))", () => {
  // Fixed golden input: a representative 32-byte userOpHash.
  const USER_OP_HASH = "0x" + "11".repeat(32);

  // Golden output: EIP-2537 G2 encoding (256 bytes) of hash_to_curve(USER_OP_HASH).
  // Computed from this repo's own bls.util; must equal the contract-side vector.
  const EXPECTED_MESSAGE_POINT =
    "0x" +
    "0000000000000000000000000000000006ee78bc8f2dec556b1fc39b04afe212" +
    "6b9817c06dc3a62eebea7015bc5e5f83209b3b632351b8b32442ea4df23425cb" +
    "00000000000000000000000000000000160a054c6de9a3df5ba20bdb88a06e0a" +
    "f04e27fccf362e3469b11ba80243ad6e78fc020c8fc79cc26c489731f7be1959" +
    "0000000000000000000000000000000001e519a10826c01e6492cf454c3b4fe2" +
    "1103add791f18c950f4202ff9e4be43e8b15185d25e6ae64f23e1c861b5e1a83" +
    "00000000000000000000000000000000134607d8f6cd2b673a9d3283ec12f593" +
    "d3bcb787d5d6198f3ad472e680eff430e95c708d1d880ac65fa080e74ef5e36b";

  it("pins the agreed DST", () => {
    expect(BLS_DST).toBe("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
  });

  it("hashes the golden userOpHash to the golden messagePoint (256-byte EIP-2537)", async () => {
    const point = await bls.G2.hashToCurve(ethers.getBytes(USER_OP_HASH), { DST: BLS_DST });
    const encoded = "0x" + Buffer.from(encodeG2Point(point)).toString("hex");

    expect(encoded).toBe(EXPECTED_MESSAGE_POINT);
    // EIP-2537 G2 point is 4 x 64-byte field elements = 256 bytes.
    expect((encoded.length - 2) / 2).toBe(256);
  });
});
