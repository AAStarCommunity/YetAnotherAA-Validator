import { bls12_381 } from "@noble/curves/bls12-381.js";

export function encodeG2Point(point: any): Uint8Array {
  const result = new Uint8Array(256);
  const affine = point.toAffine();

  const x0Bytes = hexToBytes(affine.x.c0.toString(16).padStart(96, "0"));
  const x1Bytes = hexToBytes(affine.x.c1.toString(16).padStart(96, "0"));
  const y0Bytes = hexToBytes(affine.y.c0.toString(16).padStart(96, "0"));
  const y1Bytes = hexToBytes(affine.y.c1.toString(16).padStart(96, "0"));

  result.set(x0Bytes, 16);
  result.set(x1Bytes, 80);
  result.set(y0Bytes, 144);
  result.set(y1Bytes, 208);
  return result;
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export const BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
export const bls = bls12_381;
export const sigs = bls.longSignatures;
