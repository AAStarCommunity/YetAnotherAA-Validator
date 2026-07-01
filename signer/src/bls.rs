use crate::error::SignerError;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use hex::FromHex;

/// DST must match the Node.js side EXACTLY (src/utils/bls.util.ts):
///   BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
/// Signatures are on G2, public keys on G1 (noble `longSignatures` == blst `min_pk`).
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Result of signing: all three encodings the Node.js DVT expects.
pub struct SignOutput {
    /// EIP-2537 uncompressed G2, 256 bytes → "0x…"  (the `signature` field)
    pub signature_eip2537: String,
    /// IETF/ZCash compressed G2, 96 bytes → "…" (no 0x, matches noble .toHex())
    pub signature_compact: String,
    /// IETF/ZCash compressed G1 pubkey, 48 bytes → "…" (no 0x)
    pub public_key: String,
}

/// Sign a raw 32-byte userOpHash with a raw 32-byte BLS scalar.
///
/// Mirrors the Node.js path byte-for-byte:
///   msgPoint = hashToCurve(userOpHash, DST)      // RFC 9380 SSWU RO, G2
///   sig      = msgPoint * sk                      // scalar mul
/// blst `sk.sign(msg, dst, &[])` does hash_to_curve(msg, dst) then mul internally.
/// The private key is used as the raw scalar (from_bytes), NOT HKDF key_gen.
pub fn sign_hash(sk_bytes: &[u8], user_op_hash: &[u8]) -> Result<SignOutput, SignerError> {
    if sk_bytes.len() != 32 {
        return Err(SignerError::InvalidKey("private key must be 32 bytes".into()));
    }
    if user_op_hash.len() != 32 {
        return Err(SignerError::InvalidHash("userOpHash must be 32 bytes".into()));
    }

    let sk = SecretKey::from_bytes(sk_bytes)
        .map_err(|e| SignerError::InvalidKey(format!("{:?}", e)))?;
    let pk = sk.sk_to_pk();

    // aug = &[] (no augmentation) — matches noble (POP scheme, no aug in the core sign).
    let sig: Signature = sk.sign(user_op_hash, BLS_DST, &[]);

    Ok(SignOutput {
        signature_eip2537: format!("0x{}", hex::encode(g2_to_eip2537(&sig))),
        signature_compact: hex::encode(sig.compress()),
        public_key: hex::encode(pk.compress()),
    })
}

/// Convert a blst G2 signature to EIP-2537 uncompressed layout (256 bytes):
///   [16 zero][x.c0 48][16 zero][x.c1 48][16 zero][y.c0 48][16 zero][y.c1 48]
///
/// blst `Signature::serialize()` gives 192 bytes in IETF order (c1 first):
///   x.c1(48) || x.c0(48) || y.c1(48) || y.c0(48)
/// We reorder to c0-first and pad each field element to 64 bytes.
fn g2_to_eip2537(sig: &Signature) -> [u8; 256] {
    let raw = sig.serialize(); // 192 bytes, [xc1][xc0][yc1][yc0]
    let xc1 = &raw[0..48];
    let xc0 = &raw[48..96];
    let yc1 = &raw[96..144];
    let yc0 = &raw[144..192];

    let mut out = [0u8; 256];
    out[16..64].copy_from_slice(xc0);
    out[80..128].copy_from_slice(xc1);
    out[144..192].copy_from_slice(yc0);
    out[208..256].copy_from_slice(yc1);
    out
}

/// Decode a hex private key ("0x…" or bare) into 32 bytes.
pub fn decode_sk(hex_str: &str) -> Result<Vec<u8>, SignerError> {
    let h = hex_str.trim_start_matches("0x");
    let bytes = Vec::<u8>::from_hex(h).map_err(|e| SignerError::InvalidKey(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SignerError::InvalidKey("private key must be 32 bytes".into()));
    }
    Ok(bytes)
}

/// Decode a hex userOpHash ("0x…" or bare) into 32 bytes.
pub fn decode_hash(hex_str: &str) -> Result<Vec<u8>, SignerError> {
    let h = hex_str.trim_start_matches("0x");
    let bytes = Vec::<u8>::from_hex(h).map_err(|e| SignerError::InvalidHash(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SignerError::InvalidHash("userOpHash must be 32 bytes".into()));
    }
    Ok(bytes)
}

/// Validate a compressed public key (defence in depth; rejects infinity/off-curve).
#[allow(dead_code)]
pub fn pubkey_is_valid(pk_compressed: &[u8]) -> bool {
    PublicKey::uncompress(pk_compressed)
        .map(|pk| pk.validate().is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vector generated from the Node.js path (@noble/curves longSignatures):
    //   sk          = 0x…01
    //   userOpHash  = 0x8bb1…7a81
    // See scratchpad/refvec.mjs. Rust output MUST match byte-for-byte.
    const SK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const HASH_HEX: &str = "8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81";

    const EXPECT_PUBKEY: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    const EXPECT_SIG_COMPACT: &str = "88531197560a096eeaec90e9c0eb6093bc010b7460745354c3c146589d7961cb15640b0d8c55b436871d5c0e2d9b7c3208ecb047898685515ad76c4ed47ca143e91e1e8f71f659e5c346ee4b532c8bbf5c3f376252faf0fa8b9f46bf4523c12b";
    const EXPECT_SIG_EIP2537: &str = "0x0000000000000000000000000000000008ecb047898685515ad76c4ed47ca143e91e1e8f71f659e5c346ee4b532c8bbf5c3f376252faf0fa8b9f46bf4523c12b0000000000000000000000000000000008531197560a096eeaec90e9c0eb6093bc010b7460745354c3c146589d7961cb15640b0d8c55b436871d5c0e2d9b7c320000000000000000000000000000000007ccd070ad13a66af87038b017ea84cab71c9cc4f19fa2406d58e2b46c430584e049e617270778e386a11ffee28f81880000000000000000000000000000000008633c44f58a9feb8c43e5ad4b30b9b4aa7102c4fb75c97f11ec7e52027cda8d0ee58a1b0293865ba15d18dbbaa2c165";

    #[test]
    fn matches_nodejs_golden_vector() {
        let sk = decode_sk(SK_HEX).unwrap();
        let hash = decode_hash(HASH_HEX).unwrap();
        let out = sign_hash(&sk, &hash).unwrap();

        assert_eq!(out.public_key, EXPECT_PUBKEY, "pubkey mismatch");
        assert_eq!(out.signature_compact, EXPECT_SIG_COMPACT, "compact sig mismatch");
        assert_eq!(out.signature_eip2537, EXPECT_SIG_EIP2537, "eip2537 sig mismatch");
    }
}
