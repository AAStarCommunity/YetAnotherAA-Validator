import { ethers } from "ethers";

/**
 * KMS-TEE ECDSA signer (CC-34). An ethers Signer whose secp256k1 private key is sealed in
 * the co-located KMS OP-TEE and never touches disk — the ECDSA analogue of the BLS
 * `RUST_SIGNER_URL` seam (bls.service.ts). Every signature is produced by the KMS by
 * signing a raw 32-byte digest; this class only computes the digest (tx sighash / EIP-191 /
 * EIP-712) and assembles the returned {r,s,v} back onto the payload.
 *
 * Wire contract (frozen with KMS, CC-34 comment 87e42971):
 *   POST {url}/kms/sign   Header: X-Signer-Token: <token>   (fail-closed: KMS rejects without it)
 *     req  { keeper_id?, digest: "0x"<32B> }        // KMS does NOT hash — it signs the digest
 *     resp { signature: "0x"<65B r‖s‖v, v=27/28, low-S>, address: "0x"<20B keeper EOA> }
 *
 * The key is a board singleton (KMS_KEEPER_KEY_ID / KMS_KEEPER_ADDRESS on the KMS side); this
 * signer is addressed only by its EOA, which the operator funds with ETH. When unconfigured,
 * BlockchainService falls back to a plaintext `.env` Wallet — this class is only constructed
 * when KEEPER_SIGNER_URL is set.
 */
export interface KmsEcdsaSignerOptions {
  /** KEEPER_SIGNER_URL — the KMS loopback base, e.g. http://127.0.0.1:3100. */
  url: string;
  /** The keeper EOA (KMS_KEEPER_ADDRESS) this TEE key derives to — funded with ETH. */
  address: string;
  /** KEEPER_SIGNER_TOKEN → X-Signer-Token. KMS is fail-closed: signing is rejected without it. */
  token?: string;
  /** Optional keeper_id if the KMS holds more than one keeper key (default: board singleton). */
  keeperId?: string;
  /** Injectable fetch (tests). Defaults to global fetch (Node ≥ 18). */
  fetchImpl?: typeof fetch;
  /** Per-call timeout guarding against a hung KMS socket. */
  timeoutMs?: number;
}

export class KmsEcdsaSigner extends ethers.AbstractSigner {
  /** Sync EOA, mirroring ethers.Wallet.address so BlockchainService can use it as a drop-in. */
  readonly address: string;
  private readonly url: string;
  private readonly token?: string;
  private readonly keeperId?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: KmsEcdsaSignerOptions, provider: ethers.Provider | null = null) {
    super(provider);
    // Validate + checksum up front so a bad KEEPER_ADDRESS fails fast, not on first tx.
    this.address = ethers.getAddress(opts.address);
    this.url = opts.url.replace(/\/+$/, "");
    this.token = opts.token;
    this.keeperId = opts.keeperId;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  async getAddress(): Promise<string> {
    return this.address;
  }

  connect(provider: ethers.Provider | null): KmsEcdsaSigner {
    return new KmsEcdsaSigner(
      {
        url: this.url,
        address: this.address,
        token: this.token,
        keeperId: this.keeperId,
        fetchImpl: this.fetchImpl,
        timeoutMs: this.timeoutMs,
      },
      provider
    );
  }

  /**
   * Sign a raw 32-byte digest in the KMS TEE. Defence in depth: we reject unless the returned
   * signature actually recovers to our configured keeper EOA — so a wrong-key / wrong-board KMS
   * response can never be assembled onto a broadcast tx. This is the same `ecrecover(digest,sig)
   * == address` invariant KMS golden-tests against (CC-34).
   */
  private async _signDigest(digest: string): Promise<ethers.Signature> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(digest)) {
      throw new Error(`KmsEcdsaSigner: digest must be 32-byte hex, got ${digest}`);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let json: { signature?: string; address?: string };
    try {
      const res = await this.fetchImpl(`${this.url}/kms/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.token ? { "X-Signer-Token": this.token } : {}),
        },
        body: JSON.stringify({
          digest,
          ...(this.keeperId ? { keeper_id: this.keeperId } : {}),
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`KMS /kms/sign returned HTTP ${res.status}`);
      }
      json = (await res.json()) as { signature?: string; address?: string };
    } finally {
      clearTimeout(timer);
    }

    if (!json?.signature) {
      throw new Error("KMS /kms/sign: response missing `signature`");
    }
    // KMS echoes the signing EOA — a mismatch means the board holds a different keeper key.
    if (json.address && ethers.getAddress(json.address) !== this.address) {
      throw new Error(
        `KMS keeper address mismatch: signer=${this.address}, KMS=${ethers.getAddress(json.address)}`
      );
    }
    // Signature.from parses the 65-byte r‖s‖v (v=27/28) and enforces canonical low-S.
    const sig = ethers.Signature.from(json.signature);
    const recovered = ethers.recoverAddress(digest, sig);
    if (recovered !== this.address) {
      throw new Error(
        `KMS signature does not recover to keeper EOA: expected ${this.address}, recovered ${recovered}`
      );
    }
    return sig;
  }

  async signTransaction(tx: ethers.TransactionRequest): Promise<string> {
    // sendTransaction() populates the tx first, so `from`/`to` are resolved addresses here.
    // Transaction.from() rejects a `from` field — strip it after asserting it is ours.
    const { from, ...rest } = tx;
    if (from != null && ethers.getAddress(String(from)) !== this.address) {
      throw new Error(`KmsEcdsaSigner: tx.from ${from} does not match keeper EOA ${this.address}`);
    }
    const unsigned = ethers.Transaction.from(rest as ethers.TransactionLike<string>);
    unsigned.signature = await this._signDigest(unsigned.unsignedHash);
    return unsigned.serialized;
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    // EIP-191 personal_sign digest, then TEE-sign it.
    return (await this._signDigest(ethers.hashMessage(message))).serialized;
  }

  async signTypedData(
    domain: ethers.TypedDataDomain,
    types: Record<string, ethers.TypedDataField[]>,
    value: Record<string, unknown>
  ): Promise<string> {
    return (await this._signDigest(ethers.TypedDataEncoder.hash(domain, types, value))).serialized;
  }
}
