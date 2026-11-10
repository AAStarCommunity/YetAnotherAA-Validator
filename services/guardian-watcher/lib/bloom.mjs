// Ethereum logsBloom (yellow paper §4.3.1): 2048 bits; each address and topic sets 3 bits taken
// from the first three byte pairs of its keccak256. Used by the scan as a cheap cross-check of
// getLogs (DSR, #400): a block whose bloom says a watched (address, topic) may be present, but for
// which getLogs returned nothing, is a suspected short read (for example a lagging node behind a
// load balancer), not proof of absence. A bloom false positive only costs a bounded retry.
import { ethers } from "ethers";

const BYTES = 256;

function bits(item) {
  const h = ethers.getBytes(ethers.keccak256(item));
  return [0, 2, 4].map(i => ((h[i] << 8) | h[i + 1]) & 2047);
}

/** The bloom of a set of logs ({ address, topics }), as a 0x-hex string of 256 bytes. */
export function bloomOf(logs) {
  const b = new Uint8Array(BYTES);
  const add = item => {
    for (const bit of bits(item)) b[BYTES - 1 - (bit >> 3)] |= 1 << (bit & 7);
  };
  for (const l of logs) {
    add(l.address);
    for (const t of l.topics ?? []) add(t);
  }
  return ethers.hexlify(b);
}

/** Whether `item` (an address or a 32-byte topic) may be in `bloomHex`. */
export function mayContain(bloomHex, item) {
  const b = ethers.getBytes(bloomHex);
  if (b.length !== BYTES) return true; // unreadable bloom: never a reason to trust absence
  return bits(item).every(bit => (b[BYTES - 1 - (bit >> 3)] & (1 << (bit & 7))) !== 0);
}

/**
 * Whether a log from `address` with a first topic in `topics` may be present in the block: true,
 * false, or null when the header carries no readable bloom (then nothing can be cross-checked; the
 * caller counts it, and never treats it as absence or as a reason to stop scanning).
 */
export function mayHaveLog(bloomHex, address, topics) {
  if (typeof bloomHex !== "string" || !/^0x[0-9a-fA-F]{512}$/.test(bloomHex)) return null;
  return mayContain(bloomHex, address) && topics.some(t => mayContain(bloomHex, t));
}
