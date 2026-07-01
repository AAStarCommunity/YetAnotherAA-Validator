use axum::{extract::Json, routing::get, routing::post, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{debug, info};

mod bls;
mod error;
mod keystore;

use error::SignerError;

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// userOpHash (32 bytes, hex "0x…")
    pub user_op_hash: String,
    /// node identity — selects which node_state.json key to sign with
    pub node_id: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    /// EIP-2537 uncompressed G2 (256 bytes) — the `signature` field the DVT sends on
    pub signature: String,
    /// IETF compressed G2 (96 bytes) — backward-compatible compact form
    pub signature_compact: String,
    /// IETF compressed G1 pubkey (48 bytes)
    pub public_key: String,
}

async fn sign(Json(req): Json<SignRequest>) -> Result<Json<SignResponse>, SignerError> {
    let sk = keystore::resolve_private_key(&req.node_id)?;
    let hash = bls::decode_hash(&req.user_op_hash)?;
    let out = bls::sign_hash(&sk, &hash)?;

    debug!(node_id = %req.node_id, "signed via rust signer");

    Ok(Json(SignResponse {
        signature: out.signature_eip2537,
        signature_compact: out.signature_compact,
        public_key: out.public_key,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aastar_bls_signer=debug".into()),
        )
        .init();

    let app = Router::new()
        .route("/sign", post(sign))
        .route("/health", get(|| async { "OK" }));

    // 🔒 SECURITY: bind ONLY to loopback (127.0.0.1). The signer holds node private
    // keys and MUST NOT be reachable from any external interface — only the local
    // Node.js DVT process on the same host may call it. Never change to 0.0.0.0.
    let port: u16 = std::env::var("SIGNER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5001);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    info!("🔒 BLS Signer on http://{} (LOOPBACK ONLY)", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    axum::serve(listener, app).await.expect("server failed");
}
