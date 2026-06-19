import { sigs } from "../../utils/bls.util.js";
import { BlsSigner } from "./bls-signer.interface.js";

/**
 * Default signer: the BLS private key is held in-process (from node_state.json).
 * Behaviourally identical to the pre-port signing path — getPublicKey/sign call the
 * exact same @noble/curves primitives, so output is byte-for-byte unchanged.
 */
export class LocalKeySigner implements BlsSigner {
  readonly backend = "local";
  private readonly sk: Uint8Array;

  constructor(privateKeyHex: string) {
    const h = privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex;
    // Fail-fast: a BLS12-381 secret key is a 32-byte scalar (64 hex chars). Validate
    // here instead of relying on @noble/curves to reject later — an odd-length string
    // would silently truncate and a non-hex char would parse to NaN→0 (silent bad key).
    if (!/^[0-9a-fA-F]{64}$/.test(h)) {
      throw new Error("LocalKeySigner: private key must be 32 bytes (64 hex chars)");
    }
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    this.sk = b;
  }

  async getPublicKey(): Promise<any> {
    return sigs.getPublicKey(this.sk);
  }

  async sign(messagePoint: any): Promise<any> {
    return sigs.sign(messagePoint, this.sk);
  }
}
