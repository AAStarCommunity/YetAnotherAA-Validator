import { decryptKeystore, encryptKeystore, isKeystore, Eip2335Keystore } from "./keystore.util.js";

/**
 * Verify our EIP-2335 implementation against the TWO official spec test vectors
 * (scrypt + pbkdf2). Both encrypt the same secret with the same password/salt/iv and
 * must reproduce the spec's cipher.message + checksum.message byte-for-byte; decrypt
 * must recover the secret. This is the correctness gate for a security-critical module.
 */
describe("EIP-2335 keystore (official vectors)", () => {
  // https://eips.ethereum.org/EIPS/eip-2335 — 𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑 (NFKD → "testpassword🔑")
  const PASSWORD = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
  const SECRET_HEX = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  const SALT = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
  const IV = "264daa3f303d7259501c93d997d84fe6";
  const secret = Buffer.from(SECRET_HEX, "hex");

  const VECTORS = [
    {
      kdf: "scrypt" as const,
      cipher: "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",
      checksum: "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484",
    },
    {
      kdf: "pbkdf2" as const,
      cipher: "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",
      checksum: "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",
    },
  ];

  for (const v of VECTORS) {
    it(`${v.kdf}: encrypt reproduces the spec cipher + checksum`, () => {
      const ks = encryptKeystore(secret, PASSWORD, {
        kdf: v.kdf,
        salt: Buffer.from(SALT, "hex"),
        iv: Buffer.from(IV, "hex"),
      });
      expect(ks.crypto.cipher.message).toBe(v.cipher);
      expect(ks.crypto.checksum.message).toBe(v.checksum);
    });

    it(`${v.kdf}: decrypt recovers the secret`, () => {
      const ks = encryptKeystore(secret, PASSWORD, {
        kdf: v.kdf,
        salt: Buffer.from(SALT, "hex"),
        iv: Buffer.from(IV, "hex"),
      });
      expect(Buffer.from(decryptKeystore(ks, PASSWORD)).toString("hex")).toBe(SECRET_HEX);
    });
  }

  it("wrong passphrase throws (checksum mismatch), never returns a bad key", () => {
    const ks = encryptKeystore(secret, "correct horse", { kdf: "pbkdf2" });
    expect(() => decryptKeystore(ks, "wrong")).toThrow(/wrong passphrase/i);
  });

  it("round-trips a random 32-byte key", () => {
    const key = Buffer.from("11".repeat(32), "hex");
    const ks = encryptKeystore(new Uint8Array(key), "s3cret!", { kdf: "pbkdf2" });
    expect(Buffer.from(decryptKeystore(ks, "s3cret!")).toString("hex")).toBe(key.toString("hex"));
  });

  it("rejects a non-32-byte secret", () => {
    expect(() => encryptKeystore(new Uint8Array(31), "x")).toThrow(/32 bytes/);
  });

  it("isKeystore distinguishes a keystore from a plaintext node_state", () => {
    const ks = encryptKeystore(secret, "x", { kdf: "pbkdf2" });
    expect(isKeystore(ks)).toBe(true);
    expect(isKeystore({ nodeId: "x", privateKey: "0x01" })).toBe(false);
  });
});
