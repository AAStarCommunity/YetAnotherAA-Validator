/**
 * BlsSigner — the key-CUSTODY port for BLS12-381 co-signing.
 *
 * The DVT signing ALGORITHM + wire (hashToCurve/DST/EIP-2537 — see conformance/) is the
 * fixed kernel and is NOT part of this port: every backend produces a byte-identical
 * signature for the same messagePoint. This port abstracts only WHERE the private key
 * lives and how signing is invoked, so a BLS-capable KMS/HSM can drop in (#50) without
 * touching the verifiable signing logic.
 */
export interface BlsSigner {
  /** backend id for logs/telemetry: "local" | "kms" | "hsm" | ... */
  readonly backend: string;
  /** G1 public key (noble point) for this signer's key. */
  getPublicKey(): Promise<any>;
  /** Sign a G2 messagePoint (= hashToCurve(userOpHash, DST)); returns a G2 signature point. */
  sign(messagePoint: any): Promise<any>;
}
