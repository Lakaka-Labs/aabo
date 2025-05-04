pub mod sign_transaction;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Failed to parse hex: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Signing operation failed: {0}")]
    SigningFailed(String),
    #[error("Invalid transaction")]
    InvalidTransaction(String),
    #[error("EIP-712 encoding failed: {0}")]
    Eip712Error(#[from] alloy::sol_types::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Secp256k1 signing error: {0}")]
    Secp256k1Error(#[from] k256::ecdsa::Error),
}
