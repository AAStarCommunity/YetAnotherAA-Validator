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
    // `--bench` mode (rust-signer plan b): time N signatures and print, then exit.
    // Cross-built for the target board so the hybrid perf premise is validated on the
    // REAL i.MX93 hardware, not extrapolated from a dev Mac. No server, no keys needed.
    if std::env::args().any(|a| a == "--bench") {
        run_bench();
        return;
    }

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

/// Time BLS signing throughput on this machine (used with `--bench`).
fn run_bench() {
    use std::time::Instant;
    // Fixed sk=…01 + a fixed 32-byte hash (same as the golden-vector test).
    let sk = bls::decode_sk("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("sk");
    let hash = bls::decode_hash("8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81")
        .expect("hash");
    let n: u32 = std::env::var("BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(500);

    // Warm up (first blst call pays one-time init).
    let _ = bls::sign_hash(&sk, &hash).expect("sign");

    let t0 = Instant::now();
    for _ in 0..n {
        let _ = bls::sign_hash(&sk, &hash).expect("sign");
    }
    let elapsed = t0.elapsed();
    let per = elapsed / n;
    let per_ms = per.as_secs_f64() * 1000.0;
    let per_sec = 1.0 / per.as_secs_f64();
    println!(
        "aastar-bls-signer bench: {n} sigs in {:.3}s → {:.3} ms/sig ({:.0} sig/s)",
        elapsed.as_secs_f64(),
        per_ms,
        per_sec
    );
    println!("(compare: Node.js @noble/curves path is ~150 ms/sig)");
}
