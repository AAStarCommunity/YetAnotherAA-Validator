use axum::{
    extract::Json,
    http::StatusCode,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

mod bls;
mod error;

use bls::BlsSigner;
use error::SignerError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// userOpHash (32 bytes, hex-encoded)
    pub user_op_hash: String,
    /// node_id for key lookup
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
    pub public_key: String,
}

async fn sign(
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, SignerError> {
    let signer = BlsSigner::new();
    let (sig, pubkey) = signer.sign(&req.user_op_hash, &req.node_id)?;

    Ok(Json(SignResponse {
        signature: sig,
        public_key: pubkey,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aastar_bls_signer=debug".parse().unwrap()),
        )
        .init();

    let app = Router::new()
        .route("/sign", post(sign))
        .route("/health", axum::routing::get(|| async { "OK" }));

    // 🔒 SECURITY: Listen ONLY on localhost (127.0.0.1:5001)
    // - Completely isolated from network
    // - Only local Node.js process can call
    // - No external access possible
    let addr = SocketAddr::from(([127, 0, 0, 1], 5001));

    info!("🔒 BLS Signer starting on {} (LOCAL ONLY)", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to localhost:5001");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
