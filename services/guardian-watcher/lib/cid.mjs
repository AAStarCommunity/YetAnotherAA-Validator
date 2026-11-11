// Local CID computation for disclosure records (DSR W2 ruling): CIDv1, raw codec (0x55), sha2-256,
// single block. For a file of at most 262,144 bytes that is exactly what
// `ipfs add --cid-version 1 --raw-leaves` produces; one byte more and Kubo switches to a dag-pb
// root over two blocks, so records above the cap are refused rather than published under a CID
// nobody could reproduce with this function. No dependency beyond ethers' sha256.
import { ethers } from "ethers";

export const MAX_RECORD_BYTES = 262_144;

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
function base32lower(u8) {
  let bits = 0;
  let v = 0;
  let out = "";
  for (const x of u8) {
    v = (v << 8) | x;
    bits += 8;
    while (bits >= 5) {
      out += B32[(v >>> (bits - 5)) & 31];
      bits -= 5;
    }
    v &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return out;
}

/** CIDv1 raw sha2-256 of `bytes`; throws above MAX_RECORD_BYTES. */
export function cidV1Raw(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : ethers.getBytes(bytes);
  if (u8.length > MAX_RECORD_BYTES) {
    throw new RangeError(
      `record is ${u8.length} bytes; the single-block cap is ${MAX_RECORD_BYTES}`
    );
  }
  const digest = ethers.getBytes(ethers.sha256(u8));
  return "b" + base32lower(Uint8Array.from([0x01, 0x55, 0x12, 0x20, ...digest]));
}
