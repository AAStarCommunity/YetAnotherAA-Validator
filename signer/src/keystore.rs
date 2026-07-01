use crate::bls::decode_sk;
use crate::error::SignerError;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// Directories to scan for `node_state.json` files, relative to the process cwd.
/// The DVT boots each node from `deploy/node{1,2,3}/` (see deploy/dvt-testnet.sh),
/// and a single-node dev run keeps `node_state.json` in cwd.
fn candidate_paths() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("node_state.json")];
    for n in 1..=9 {
        v.push(PathBuf::from(format!("deploy/node{n}/node_state.json")));
    }
    // Allow an explicit override dir (e.g. an isolated hybrid-test node).
    if let Ok(dir) = std::env::var("NODE_STATE_DIR") {
        v.insert(0, PathBuf::from(dir).join("node_state.json"));
    }
    v
}

/// Resolve the 32-byte BLS private key for a given nodeId by scanning known
/// `node_state.json` locations and matching the `nodeId` field. The private key
/// NEVER leaves this process — only the signature/pubkey are returned to the DVT.
pub fn resolve_private_key(node_id: &str) -> Result<Vec<u8>, SignerError> {
    for path in candidate_paths() {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&content) else {
            continue;
        };

        // Match on nodeId so a multi-node host signs with the CORRECT key, never
        // "the first file found" (which would silently cross-sign under the wrong key).
        let matches = json.get("nodeId").and_then(|v| v.as_str()) == Some(node_id);
        if !matches {
            continue;
        }

        let Some(pk_hex) = json.get("privateKey").and_then(|v| v.as_str()) else {
            return Err(SignerError::InvalidKey(format!(
                "node_state.json for {node_id} has no privateKey field"
            )));
        };
        return decode_sk(pk_hex);
    }

    Err(SignerError::KeyNotFound(node_id.to_string()))
}
