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

    /// One golden vector from the Node.js path (@noble/curves longSignatures).
    /// Rust output MUST match byte-for-byte (BLS is deterministic → identical = correct).
    struct Vec_ {
        sk: &'static str,
        hash: &'static str,
        pubkey: &'static str,
        compact: &'static str,
        eip2537: &'static str,
    }

    // Generated from scratchpad refvec scripts against @noble/curves. Varied scalars
    // (small / near-order / mid) and hashes (fixed / zero / all-FF / deadbeef) to catch
    // any encoding or endianness drift, not just the happy path.
    const VECTORS: &[Vec_] = &[
        Vec_ {
            sk: "0000000000000000000000000000000000000000000000000000000000000001",
            hash: "8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81",
            pubkey: "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            compact: "88531197560a096eeaec90e9c0eb6093bc010b7460745354c3c146589d7961cb15640b0d8c55b436871d5c0e2d9b7c3208ecb047898685515ad76c4ed47ca143e91e1e8f71f659e5c346ee4b532c8bbf5c3f376252faf0fa8b9f46bf4523c12b",
            eip2537: "0x0000000000000000000000000000000008ecb047898685515ad76c4ed47ca143e91e1e8f71f659e5c346ee4b532c8bbf5c3f376252faf0fa8b9f46bf4523c12b0000000000000000000000000000000008531197560a096eeaec90e9c0eb6093bc010b7460745354c3c146589d7961cb15640b0d8c55b436871d5c0e2d9b7c320000000000000000000000000000000007ccd070ad13a66af87038b017ea84cab71c9cc4f19fa2406d58e2b46c430584e049e617270778e386a11ffee28f81880000000000000000000000000000000008633c44f58a9feb8c43e5ad4b30b9b4aa7102c4fb75c97f11ec7e52027cda8d0ee58a1b0293865ba15d18dbbaa2c165",
        },
        Vec_ {
            sk: "0000000000000000000000000000000000000000000000000000000000000002",
            hash: "0000000000000000000000000000000000000000000000000000000000000000",
            pubkey: "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            compact: "8492cab20cc72f7b3204e1aba4fcd215a9d35cae6cedb6bb8e814d75bdf703e61114f017d7ad51756863061bc4eb327812b09a1dfe1349e6021a6d16a64124243fef4f49020ca94b476a6a6fd882810e540d321ba5be3e03d3364d0106bbbdc7",
            eip2537: "0x0000000000000000000000000000000012b09a1dfe1349e6021a6d16a64124243fef4f49020ca94b476a6a6fd882810e540d321ba5be3e03d3364d0106bbbdc7000000000000000000000000000000000492cab20cc72f7b3204e1aba4fcd215a9d35cae6cedb6bb8e814d75bdf703e61114f017d7ad51756863061bc4eb3278000000000000000000000000000000000090f7de5df31110a40e24d77780bdf9a348934e98d1a9c2cad9d691a152e6adf2d5872ebb0c91f3e18cd9b466b9849d00000000000000000000000000000000082255f2e51e1c697bd80c306c28fe141914ad180a8681e09e51e19dc651cfaf010dc89711fc9fa475e041a4ca73496e",
        },
        Vec_ {
            sk: "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            pubkey: "b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            compact: "a0af3443ffbeac150d95be71508608b6825348d33698a016836d58b669cf3dfdf011e5493df23f42e286be35368553e110fb7e37155c4c636b3ba08bbccf876fdc76865107396eb7c47e9b7379a5398e47b94ec4f354085295030b6e6d473524",
            eip2537: "0x0000000000000000000000000000000010fb7e37155c4c636b3ba08bbccf876fdc76865107396eb7c47e9b7379a5398e47b94ec4f354085295030b6e6d4735240000000000000000000000000000000000af3443ffbeac150d95be71508608b6825348d33698a016836d58b669cf3dfdf011e5493df23f42e286be35368553e1000000000000000000000000000000000690ce29b7753098de50f9f17289d59e8875a6760e4fb28ed9f10bdaf5c0b06e6c202576d8769652cf10b6a4b8a6bb130000000000000000000000000000000014efbc4bc6cb31c81be88e08d2aa18e60c17eafac99d91e98ec6af7fa60b26d6b899d8e20ba4feef544930abde511089",
        },
        Vec_ {
            sk: "1111111111111111111111111111111111111111111111111111111111111111",
            hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            pubkey: "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4",
            compact: "ae2c7d982a2933d77102b2cf9c081bbd01aa23c15e5d2c3eaf7534929de2f742a5fe616cdf6bf1b19bf7625928afbc5b0bb47b1cfd36ee4d79e1f651d0b78a0e7391b4c99ea1fdba70ec8555320bdaefc7a95f28af6fb756b35ef39791394e8a",
            eip2537: "0x000000000000000000000000000000000bb47b1cfd36ee4d79e1f651d0b78a0e7391b4c99ea1fdba70ec8555320bdaefc7a95f28af6fb756b35ef39791394e8a000000000000000000000000000000000e2c7d982a2933d77102b2cf9c081bbd01aa23c15e5d2c3eaf7534929de2f742a5fe616cdf6bf1b19bf7625928afbc5b00000000000000000000000000000000093af0a67d4a76837f556e44e7eb9b91662ff45918c33473aa83912009718a5087b4b13c2418fabf30d4d68497b581fa000000000000000000000000000000001700279b464b09fd3a0f63f356f463ebb355b9aba3b112d08fca6fb18765388d621d3eee8e45781e63888a2143253931",
        },
    ];

    #[test]
    fn matches_nodejs_golden_vectors() {
        for (i, v) in VECTORS.iter().enumerate() {
            let sk = decode_sk(v.sk).unwrap();
            let hash = decode_hash(v.hash).unwrap();
            let out = sign_hash(&sk, &hash).unwrap();
            assert_eq!(out.public_key, v.pubkey, "vector {i}: pubkey mismatch");
            assert_eq!(out.signature_compact, v.compact, "vector {i}: compact sig mismatch");
            assert_eq!(out.signature_eip2537, v.eip2537, "vector {i}: eip2537 sig mismatch");
        }
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(sign_hash(&[0u8; 31], &[0u8; 32]).is_err(), "31-byte key must fail");
        assert!(sign_hash(&[0u8; 33], &[0u8; 32]).is_err(), "33-byte key must fail");
        assert!(decode_sk("00").is_err(), "short hex key must fail");
    }

    #[test]
    fn rejects_bad_hash_length() {
        let sk = decode_sk(VECTORS[0].sk).unwrap();
        assert!(sign_hash(&sk, &[0u8; 31]).is_err(), "31-byte hash must fail");
        assert!(sign_hash(&sk, &[0u8; 33]).is_err(), "33-byte hash must fail");
        assert!(decode_hash("0xzz").is_err(), "non-hex hash must fail");
    }

    #[test]
    fn decode_accepts_0x_prefix_and_bare() {
        assert_eq!(decode_sk(VECTORS[0].sk).unwrap(), decode_sk(&format!("0x{}", VECTORS[0].sk)).unwrap());
    }

    #[test]
    fn output_lengths_are_exact() {
        let sk = decode_sk(VECTORS[0].sk).unwrap();
        let out = sign_hash(&sk, &decode_hash(VECTORS[0].hash).unwrap()).unwrap();
        assert_eq!(out.public_key.len(), 96, "G1 compressed = 48 bytes = 96 hex");
        assert_eq!(out.signature_compact.len(), 192, "G2 compressed = 96 bytes = 192 hex");
        assert_eq!(out.signature_eip2537.len(), 2 + 512, "EIP-2537 G2 = 256 bytes = 512 hex + 0x");
    }

    // Stable-Rust micro-benchmark (no nightly `#[bench]`). Ignored by default; run on the
    // TARGET board to validate the hybrid perf premise vs the ~150ms Node path:
    //   cargo test --release -- --ignored --nocapture bench_sign
    #[test]
    #[ignore]
    fn bench_sign() {
        use std::time::Instant;
        let sk = decode_sk(VECTORS[0].sk).unwrap();
        let hash = decode_hash(VECTORS[0].hash).unwrap();
        let n = 200;
        // warm up (first blst call pays one-time init)
        let _ = sign_hash(&sk, &hash).unwrap();
        let t0 = Instant::now();
        for _ in 0..n {
            let _ = sign_hash(&sk, &hash).unwrap();
        }
        let per = t0.elapsed() / n;
        println!("sign_hash: {n} sigs, {:?}/sig ({:.1} sig/s)", per, 1.0 / per.as_secs_f64());
    }
}
