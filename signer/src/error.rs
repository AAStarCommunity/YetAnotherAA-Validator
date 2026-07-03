use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Key not found for node: {0}")]
    KeyNotFound(String),

    #[error("BLS operation failed: {0}")]
    BlsError(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for SignerError {
    fn into_response(self) -> Response {
        error!("Signer error: {:?}", self);

        let (status, error_message) = match self {
            SignerError::InvalidHash(msg) => (StatusCode::BAD_REQUEST, msg),
            SignerError::InvalidKey(msg) => (StatusCode::BAD_REQUEST, msg),
            SignerError::KeyNotFound(node_id) => (
                StatusCode::NOT_FOUND,
                format!("Key not found for node: {}", node_id),
            ),
            SignerError::BlsError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            SignerError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

impl From<blst::BLST_ERROR> for SignerError {
    fn from(err: blst::BLST_ERROR) -> Self {
        SignerError::BlsError(format!("{:?}", err))
    }
}
