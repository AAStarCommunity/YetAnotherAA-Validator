import {
  createHash,
  createCipheriv,
  createDecipheriv,
  scryptSync,
  pbkdf2Sync,
  randomBytes,
  randomUUID,
} from "crypto";

/**
 * EIP-2335 BLS12-381 keystore (#50 ④, #5). Encrypts a 32-byte BLS secret at rest with
 * an operator passphrase so a leaked disk/backup does NOT expose the key. Same format
 * Ethereum validators use, same curve — a natural fit for the DVT's BLS key.
 *
 * Implemented on Node's built-in crypto (scrypt/pbkdf2 + aes-128-ctr + sha256) and
 * VERIFIED byte-for-byte against the two official EIP-2335 test vectors (see spec).
 * No third-party crypto dependency.
 *
 * SECURITY BOUNDARY: this protects the key AT REST only. The passphrase must NOT be
 * stored next to the file — supply it at boot via NODE_KEY_PASSPHRASE (env / systemd
 * credential). It does not protect against a compromised running process (the key is
 * decrypted in memory to sign) nor against someone who has the passphrase.
 */
export interface Eip2335Keystore {
  crypto: {
    kdf: {
      function: "scrypt" | "pbkdf2";
      params: Record<string, unknown>;
      message: "";
    };
    checksum: { function: "sha256"; params: Record<string, never>; message: string };
    cipher: { function: "aes-128-ctr"; params: { iv: string }; message: string };
  };
  pubkey?: string;
  uuid: string;
  version: 4;
  description?: string;
}

/** EIP-2335 password prep: NFKD-normalize, strip C0/C1 control codes, UTF-8 encode. */
function normalizePassword(pw: string): Buffer {
  const nfkd = pw.normalize("NFKD");
  const stripped = [...nfkd]
    .filter(ch => {
      const c = ch.codePointAt(0)!;
      return !(c <= 0x1f || (c >= 0x7f && c <= 0x9f));
    })
    .join("");
  return Buffer.from(stripped, "utf8");
}

/** scrypt memory ≈ 128·N·r. For N=262144,r=8 that's ~256 MB; give Node headroom. */
function deriveKey(kdf: Eip2335Keystore["crypto"]["kdf"], password: Buffer, salt: Buffer): Buffer {
  const p = kdf.params as Record<string, number>;
  const dklen = Number(p.dklen ?? 32);
  if (kdf.function === "scrypt") {
    return scryptSync(password, salt, dklen, {
      N: Number(p.n),
      r: Number(p.r),
      p: Number(p.p),
      maxmem: 512 * 1024 * 1024,
    });
  }
  // pbkdf2, prf = hmac-sha256 (the only prf EIP-2335 defines)
  return pbkdf2Sync(password, salt, Number(p.c), dklen, "sha256");
}

/**
 * Decrypt an EIP-2335 keystore to the raw 32-byte BLS secret. Throws on a wrong
 * passphrase (checksum mismatch) — never returns a garbage key.
 */
export function decryptKeystore(ks: Eip2335Keystore, password: string): Uint8Array {
  const salt = Buffer.from(String(ks.crypto.kdf.params.salt), "hex");
  const dk = deriveKey(ks.crypto.kdf, normalizePassword(password), salt);
  const cipherMsg = Buffer.from(ks.crypto.cipher.message, "hex");

  // checksum = sha256(decryption_key[16:32] ‖ cipher.message) — verifies the passphrase.
  const checksum = createHash("sha256")
    .update(Buffer.concat([dk.subarray(16, 32), cipherMsg]))
    .digest("hex");
  if (checksum !== ks.crypto.checksum.message) {
    throw new Error("keystore: wrong passphrase (checksum mismatch)");
  }

  // AES-128-CTR with key = decryption_key[0:16], iv from the keystore.
  const iv = Buffer.from(ks.crypto.cipher.params.iv, "hex");
  const decipher = createDecipheriv("aes-128-ctr", dk.subarray(0, 16), iv);
  const secret = Buffer.concat([decipher.update(cipherMsg), decipher.final()]);
  return new Uint8Array(secret);
}

export interface EncryptOpts {
  kdf?: "scrypt" | "pbkdf2";
  pubkey?: string;
  description?: string;
  /** Deterministic salt/iv/uuid — ONLY for tests / golden-vector verification. */
  salt?: Buffer;
  iv?: Buffer;
  uuid?: string;
}

/** Encrypt a 32-byte BLS secret into an EIP-2335 keystore. */
export function encryptKeystore(
  secret: Uint8Array,
  password: string,
  opts: EncryptOpts = {}
): Eip2335Keystore {
  if (secret.length !== 32) {
    throw new Error("keystore: BLS secret must be 32 bytes");
  }
  const kdfFn = opts.kdf ?? "scrypt";
  const salt = opts.salt ?? randomBytes(32);
  const iv = opts.iv ?? randomBytes(16);
  const params: Record<string, unknown> =
    kdfFn === "scrypt"
      ? { dklen: 32, n: 262144, p: 1, r: 8, salt: salt.toString("hex") }
      : { dklen: 32, c: 262144, prf: "hmac-sha256", salt: salt.toString("hex") };

  const dk = deriveKey({ function: kdfFn, params, message: "" }, normalizePassword(password), salt);
  const cipher = createCipheriv("aes-128-ctr", dk.subarray(0, 16), iv);
  const cipherMsg = Buffer.concat([cipher.update(Buffer.from(secret)), cipher.final()]);
  const checksum = createHash("sha256")
    .update(Buffer.concat([dk.subarray(16, 32), cipherMsg]))
    .digest("hex");

  return {
    crypto: {
      kdf: { function: kdfFn, params, message: "" },
      checksum: { function: "sha256", params: {}, message: checksum },
      cipher: {
        function: "aes-128-ctr",
        params: { iv: iv.toString("hex") },
        message: cipherMsg.toString("hex"),
      },
    },
    pubkey: opts.pubkey,
    uuid: opts.uuid ?? randomUUID(),
    version: 4,
    description: opts.description,
  };
}

/** Structural check — is this object an EIP-2335 keystore (vs a plaintext node_state)? */
export function isKeystore(obj: unknown): obj is Eip2335Keystore {
  const o = obj as Eip2335Keystore;
  return !!o && typeof o === "object" && o.version === 4 && !!o.crypto?.cipher?.message;
}
