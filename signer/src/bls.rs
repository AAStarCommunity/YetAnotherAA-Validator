use crate::error::SignerError;
use blst::*;
use hex::{FromHex, ToHex};
use sha2::{Digest, Sha256};
use std::fs;
use tracing::debug;

const BLS_DST: &[u8] = b"BLS_SIG_BLSPOP_SHA256G2_RO_POP_";

pub struct BlsSigner;

impl BlsSigner {
    pub fn new() -> Self {
        Self
    }

    /// Sign a userOpHash with the node's BLS private key
    /// Returns (signature_hex, pubkey_hex)
    pub fn sign(&self, user_op_hash: &str, node_id: &str) -> Result<(String, String), SignerError> {
        // 1. Load node's private key from node_state.json
        let private_key = self.load_node_key(node_id)?;

        // 2. Decode userOpHash (hex → bytes)
        let hash_bytes = Vec::<u8>::from_hex(user_op_hash.trim_start_matches("0x"))
            .map_err(|e| SignerError::InvalidHash(e.to_string()))?;

        if hash_bytes.len() != 32 {
            return Err(SignerError::InvalidHash(
                "userOpHash must be 32 bytes".to_string(),
            ));
        }

        debug!(
            user_op_hash = user_op_hash,
            node_id = node_id,
            "Signing userOpHash"
        );

        // 3. Hash userOpHash with SHA256 (matches @noble/curves behavior)
        let mut hasher = Sha256::new();
        hasher.update(&hash_bytes);
        let message = hasher.finalize();

        // 4. BLS sign
        let sk = SecretKey::key_gen(&private_key, BLS_DST)?;
        let pk = sk.sk_to_pk();
        let signature = sk.sign(&message, BLS_DST, &[])?;

        // 5. Encode to hex (EIP-2537 format)
        let sig_hex = self.encode_g2_point(&signature)?;
        let pk_hex = self.encode_g1_point(&pk)?;

        Ok((sig_hex, pk_hex))
    }

    /// Load node's BLS private key from node_state.json
    fn load_node_key(&self, node_id: &str) -> Result<Vec<u8>, SignerError> {
        // Try multiple locations
        let possible_paths = vec![
            format!("deploy/node1/node_state.json"),
            format!("deploy/node2/node_state.json"),
            format!("deploy/node3/node_state.json"),
            format!("node_state.json"),
        ];

        for path in possible_paths {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(private_key) = json.get("privateKey").and_then(|v| v.as_str()) {
                        let key_bytes =
                            Vec::<u8>::from_hex(private_key.trim_start_matches("0x"))
                                .map_err(|e| SignerError::InvalidKey(e.to_string()))?;

                        if key_bytes.len() == 32 {
                            return Ok(key_bytes);
                        }
                    }
                }
            }
        }

        Err(SignerError::KeyNotFound(node_id.to_string()))
    }

    /// Encode G2 point to hex (256 bytes, EIP-2537 format)
    fn encode_g2_point(&self, point: &P2_Affine) -> Result<String, SignerError> {
        let mut out = [0u8; 256];
        point.compress(&mut out);
        Ok(format!("0x{}", out.to_hex()))
    }

    /// Encode G1 point to hex (128 bytes, EIP-2537 format)
    fn encode_g1_point(&self, point: &P1_Affine) -> Result<String, SignerError> {
        let mut out = [0u8; 128];
        point.compress(&mut out);
        Ok(format!("0x{}", out.to_hex()))
    }
}
