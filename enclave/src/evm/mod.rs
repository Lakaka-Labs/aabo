mod sign_eth_transaction;
mod tx_serde_test;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Failed to load private key: {0}")]
    PrivateKeyLoadError(String),
    // #[error("Invalid private key format: {0}")]
    // InvalidPrivateKey(#[from] alloy::signers::wallet::key::ParseError),
    #[error("Failed to parse hex: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Signing operation failed: {0}")]
    SigningFailed(String), // Catch-all for signing library errors
    #[error("EIP-712 encoding failed: {0}")]
    Eip712Error(#[from] alloy::sol_types::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Secp256k1 signing error: {0}")]
    Secp256k1Error(#[from] k256::ecdsa::Error),
}